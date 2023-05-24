<?php
declare(strict_types=1);

namespace Hyperf\JWTAuth;

use Hyperf\Contract\ConfigInterface;
use Psr\Container\ContainerInterface;

/**
 * Author lujihong
 * Description
 */
abstract class AbstractJWT implements JWTInterface
{
    /**
     * @var string
     */
    public string $tokenPrefix = 'Bearer';

    public string $tokenScenePrefix = 'jwt_scene';

    /**
     * @var array Supported algorithms
     */
    private array $supportedAlgs = [
        'HS256' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
        'HS384' => \Lcobucci\JWT\Signer\Hmac\Sha384::class,
        'HS512' => \Lcobucci\JWT\Signer\Hmac\Sha512::class,
        'ES256' => \Lcobucci\JWT\Signer\Ecdsa\Sha256::class,
        'ES384' => \Lcobucci\JWT\Signer\Ecdsa\Sha384::class,
        'ES512' => \Lcobucci\JWT\Signer\Ecdsa\Sha512::class,
        'RS256' => \Lcobucci\JWT\Signer\Rsa\Sha256::class,
        'RS384' => \Lcobucci\JWT\Signer\Rsa\Sha384::class,
        'RS512' => \Lcobucci\JWT\Signer\Rsa\Sha512::class,
    ];

    // 对称算法名称
    private array $symmetryAlgs = [
        'HS256',
        'HS384',
        'HS512'
    ];

    // 非对称算法名称
    private array $asymmetricAlgs = [
        'RS256',
        'RS384',
        'RS512',
        'ES256',
        'ES384',
        'ES512',
    ];

    /**
     * 当前token生成token的场景值
     * @var string
     */
    private string $scene = 'default';

    /**
     * @var string
     */
    protected string $scenePrefix = 'scene';

    /**
     * @var ContainerInterface
     */
    private ContainerInterface $container;

    /**
     * @var ConfigInterface
     */
    protected ConfigInterface $config;

    /**
     * jwt配置前缀
     * @var string
     */
    protected string $configPrefix = 'jwt';

    /**
     * @param ContainerInterface $container
     * @throws \Psr\Container\ContainerExceptionInterface
     * @throws \Psr\Container\NotFoundExceptionInterface
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->config = $this->container->get(ConfigInterface::class);

        // 合并场景配置，并且兼容2.0.6以下的配置
        $config = $this->config->get($this->configPrefix);
        if (empty($config['supported_algs'])) {
            $config['supported_algs'] = $this->supportedAlgs;
        }
        if (empty($config['symmetry_algs'])) {
            $config['symmetry_algs'] = $this->symmetryAlgs;
        }
        if (empty($config['asymmetric_algs'])) {
            $config['asymmetric_algs'] = $this->asymmetricAlgs;
        }
        if (empty($config['blacklist_prefix'])) {
            $config['blacklist_prefix'] = 'mineadmin_jwt';
        }
        $scenes = $config['scene'];
        unset($config['scene']);
        foreach ($scenes as $key => $scene) {
            $sceneConfig = array_merge($config, $scene);
            $this->setSceneConfig($key, $sceneConfig);
        }
    }

    /**
     * @param ContainerInterface $container
     * @return $this
     */
    public function setContainer(ContainerInterface $container): self
    {
        $this->container = $container;
        return $this;
    }

    /**
     * @return ContainerInterface
     */
    public function getContainer(): ContainerInterface
    {
        return $this->container;
    }

    /**
     * 设置场景值
     * @param string $scene
     */
    public function setScene(string $scene): static
    {
        $this->scene = $scene;
        return $this;
    }

    /**
     * 获取当前场景值
     * @return string
     */
    public function getScene(): string
    {
        return $this->scene;
    }

    /**
     * @param string $scene
     * @param null $value
     * @return $this
     */
    public function setSceneConfig(string $scene = 'default', $value = null): static
    {
        $this->config->set("{$this->configPrefix}.{$this->scenePrefix}.{$scene}", $value);
        return $this;
    }

    /**
     * @param string $scene
     * @return mixed
     */
    public function getSceneConfig(string $scene = 'default'): mixed
    {
        return $this->config->get("{$this->configPrefix}.{$this->scenePrefix}.{$scene}");
    }
}
