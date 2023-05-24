<?php
declare(strict_types=1);

namespace Hyperf\JWTAuth;

use Hyperf\Context\Context;
use Hyperf\HttpServer\Contract\RequestInterface;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Psr\SimpleCache\InvalidArgumentException;
use Hyperf\JWTAuth\Exception\JWTException;
use Hyperf\JWTAuth\Exception\TokenValidException;
use Hyperf\JWTAuth\Util\JWTUtil;
use Psr\Container\ContainerInterface;
use Hyperf\JWTAuth\Util\TimeUtil;

/**
 * Author lujihong
 * Description
 */
class JWT extends AbstractJWT
{
    public RequestInterface $request;
    public BlackList $blackList;
    public const PREFIX = '_jwt_info';

    public function __construct(ContainerInterface $container, BlackList $blackList)
    {
        parent::__construct($container);
        $this->request = $this->getContainer()->get(RequestInterface::class);
        $this->blackList = $blackList;
    }

    /**
     * 生成token
     * @param array $claims
     * @param bool $isInsertSsoBlack 是否把单点登录生成的token加入黑名单
     * @param bool $isConversionString 是否把token强制转换成string类型
     * @return Token|string
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function getToken(array $claims, bool $isInsertSsoBlack = true, bool $isConversionString = true): Token|string
    {
        $config = $this->getSceneConfig($this->getScene());
        if (empty($config)) {
            throw new JWTException("The jwt scene [{$this->getScene()}] not found", 400);
        }
        $loginType = $config['login_type'];
        $ssoKey = $config['sso_key'];
        if ($loginType === 'mpop') { // 多点登录,场景值加上一个唯一id
            $uniqueId = uniqid($this->getScene() . '_', true);
        } else { // 单点登录
            if (empty($claims[$ssoKey])) {
                throw new JWTException("There is no {$ssoKey} key in the claims", 400);
            }
            $uniqueId = $this->getScene() . "_" . $claims[$ssoKey];
        }
        $signer = new $config['supported_algs'][$config['alg']];
        $time = new \DateTimeImmutable();
        $builder = JWTUtil::getBuilder($signer, $this->getKey($config))
            ->identifiedBy($uniqueId) // 设置jwt的jti
            ->issuedAt($time)// (iat claim) 发布时间
            ->canOnlyBeUsedAfter($time)// (nbf claim) 在此之前不可用
            ->expiresAt($time->modify(sprintf('+%s second', $config['ttl'])));// (exp claim) 到期时间

        $claims[$this->tokenScenePrefix] = $this->getScene(); // 加入场景值
        foreach ($claims as $k => $v) {
            $builder = $builder->withClaim($k, $v); // 自定义数据
        }

        $token = $builder->getToken($signer, $this->getKey($config)); // Retrieves the generated token

        // 单点登录要把所有的以前生成的token都失效
        if ($loginType === 'sso' && $isInsertSsoBlack) {
            $this->blackList->addTokenBlack($token, $config);
        }

        return $isConversionString ? $token->toString() : $token;
    }

    /**
     * 验证token
     * @param string|null $token
     * @param string|null $scene
     * @param bool $validate
     * @param bool $independentTokenVerify true时会验证当前场景配置是否是生成当前的token的配置，需要配合自定义中间件实现，false会根据当前token拿到原来的场景配置，并且验证当前token
     * @return bool
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function checkToken(string $token = null, string $scene = null, bool $validate = true, bool $independentTokenVerify = false): ?bool
    {
        try {
            if ($token) {
                $token = JWTUtil::handleToken($token, $this->tokenPrefix);
            }
            $token = $token ?: $this->getHeaderToken();
            $tokenObj = $this->getTokenObj($token);
            $scene = $scene ?: $this->getScene();
            $config = $this->getSceneConfig($scene);
            $claims = $tokenObj->claims();
            $claimsData = $claims->all();
            $signer = new $config['supported_algs'][$config['alg']];

            // 验证token是否存在黑名单
            if ($config['blacklist_enabled'] && $validate && $this->blackList->hasTokenBlack($claimsData, $config)) {
                throw new TokenValidException('Token has been blacked out', 4000);
            }

            //token验证
            if ($validate && !$this->validateToken($signer, $this->getKey($config), $token)) {
                throw new TokenValidException('Token authentication does not pass', 4001);
            }

            // 获取当前环境的场景配置并且验证该token是否是该配置生成的
            if ($independentTokenVerify && isset($claimsData['jwt_scene'])) {
                if ($claimsData['jwt_scene'] !== $scene) {
                    throw new TokenValidException('Token scenario value is not legal', 4002);
                }
            }

            //将解析的结果保存到协程上下文
            Context::set($this->getContextKey($scene), $claimsData);

            //获取token动态有效时间
            if ($claims->has(RegisteredClaims::EXPIRATION_TIME)) {
                $dateTimeImmutable = $claims->get(RegisteredClaims::EXPIRATION_TIME);
                $timeUtil = TimeUtil::timestamp($dateTimeImmutable->getTimestamp());
                $timeRemaining = $timeUtil->max(TimeUtil::now())->diffInSeconds();

                //token 10分钟后失效时提醒前端覆盖掉原来的token
                if ($timeRemaining < 600) {
                    //token自动续期，在响应头中返回ExchangeToken，前端拿到后覆盖到本地保存
                    Context::set($this->getRefreshedTokenKey($scene), $this->refreshToken($token));
                }
            }
        } catch (\Exception $e) {
            throw new \Exception($e->getMessage(), $e->getCode(), $e->getPrevious());
        }
        return true;
    }

    /**
     * 刷新token
     * @param string|null $token
     * @return Token|string
     * @throws InvalidArgumentException
     */
    public function refreshToken(string $token = null): Token|string
    {
        try {
            if ($token) {
                $token = JWTUtil::handleToken($token, $this->tokenPrefix);
                $claims = $this->getTokenObj($token)->claims()->all();
            } else {
                $key = $this->getContextKey();
                if (Context::has($key)) {
                    $claims = Context::get($key);
                } else {
                    $claims = $this->getTokenObj($this->getHeaderToken())->claims()->all();
                }
            }
            unset($claims['iat'], $claims['nbf'], $claims['exp'], $claims['jti']);
            $token = $this->getToken($claims);
        } catch (\Exception $e) {
            throw new \Exception($e->getMessage(), $e->getCode(), $e->getPrevious());
        }
        return $token;
    }

    /**
     * 让token失效
     * @param string|null $token
     * @param string|null $scene
     * @return bool
     * @throws InvalidArgumentException
     */
    public function logout(string $token = null, string $scene = null): bool
    {
        try {
            if ($token) {
                $token = JWTUtil::handleToken($token, $this->tokenPrefix);
            }
            $config = $this->getSceneConfig($scene ?? $this->getScene());
            $this->blackList->addTokenBlack($this->getTokenObj($token), $config);
        } catch (\Exception $e) {
            return false;
        }
        return true;
    }

    /**
     * 获取token动态有效时间
     * @param string|null $token
     * @return float|int
     */
    public function getTokenDynamicCacheTime(string $token = null): float|int
    {
        if ($token) {
            $token = JWTUtil::handleToken($token, $this->tokenPrefix);
        }
        $token = $token ?: $this->getHeaderToken();
        $claims = $this->getTokenObj($token)->claims();
        if ($claims->has(RegisteredClaims::EXPIRATION_TIME)) {
            $dateTimeImmutable = $claims->get(RegisteredClaims::EXPIRATION_TIME);
            $timeUtil = TimeUtil::timestamp($dateTimeImmutable->getTimestamp());
            return $timeUtil->max(TimeUtil::now())->diffInSeconds();
        }
        return -1;
    }

    /**
     * 获取已刷新的token
     * @return string
     */
    public function getRefreshedTokenKey(string $scene = 'default')
    {
        return $this->config->get("{$this->configPrefix}.{$this->scenePrefix}.{$scene}.refreshed_token_key");
    }

    /**
     * 根据上下文获取新token
     * @param string $scene
     * @return mixed|null
     */
    public function getTokenByContext(string $scene = 'default'): ?string
    {
        $key = $this->getRefreshedTokenKey($scene);
        return Context::has($key) ? Context::get($key) : null;
    }

    /**
     * 获取协程上下文key
     * @return string
     */
    public function getContextKey($scene = null): string
    {
        return $scene ?: $this->getScene() . self::PREFIX;
    }

    /**
     * 获取jwt token解析的data
     * @param string|null $token
     * @return array
     */
    public function getParserData(string $token = null): array
    {
        if ($token) {
            $token = JWTUtil::handleToken($token, $this->tokenPrefix);
            $claims = $this->getTokenObj($token)->claims()->all();
            Context::set($this->getContextKey(), $claims); //将解析的结果保存到协程上下文
            return $claims;
        }

        $key = $this->getContextKey();
        if (Context::has($key)) {
            return Context::get($key);
        }

        $claims = $this->getTokenObj($this->getHeaderToken())->claims()->all();
        Context::set($this->getContextKey(), $claims); //将解析的结果保存到协程上下文
        return $claims;
    }

    /**
     * 获取缓存时间
     * @param string|null $scene
     * @return mixed
     */
    public function getTTL(string $scene = null): mixed
    {
        return $this->getSceneConfig($scene ?: $this->getScene())['ttl'];
    }

    /**
     * 获取对应算法需要的key
     * @param array $config
     * @param string $type 配置keys里面的键，获取私钥或者公钥。private-私钥，public-公钥
     * @return InMemory|null
     */
    private function getKey(array $config, string $type = 'private'): ?InMemory
    {
        $key = null;

        // 对称算法
        if (in_array($config['alg'], $config['symmetry_algs'], true)) {
            $key = InMemory::base64Encoded($config['secret']);
        }

        // 非对称
        if (in_array($config['alg'], $config['asymmetric_algs'], true)) {
            $key = InMemory::base64Encoded($config['keys'][$type]);
        }

        return $key;
    }

    /**
     * 获取Token对象
     * @param string|null $token
     * @return Token
     */
    private function getTokenObj(string $token = null): Token
    {
        $config = $this->getSceneConfig($this->getScene());
        $signer = new $config['supported_algs'][$config['alg']];
        return JWTUtil::getParser($signer, $this->getKey($config))->parse($token ?: $this->getHeaderToken());
    }

    /**
     * 获取http头部token
     * @return string
     */
    private function getHeaderToken(): string
    {
        $token = $this->request->getHeaderLine('Authorization') ?? '';
        $token = JWTUtil::handleToken($token, $this->tokenPrefix);
        if ($token === false) {
            throw new JWTException('A token is required', 400);
        }
        return $token;
    }

    /**
     * 验证jwt token的data部分
     * @param Signer $signer
     * @param Key $key
     * @param string $token
     * @return bool
     */
    private function validateToken(Signer $signer, Key $key, string $token): bool
    {
        return JWTUtil::getValidationData($signer, $key, $token);
    }
}
