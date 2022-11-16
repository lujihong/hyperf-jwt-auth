<?php
declare(strict_types=1);

namespace Hyperf\JWTAuth\Util;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Parser;

/**
 * Author lujihong
 * Description JWT工具类
 */
class JWTUtil
{
    /**
     * claims对象转换成数组
     * @param array $claims
     * @return array
     */
    public static function claimsToArray(array $claims): array
    {
        foreach ($claims as $k => $claim) {
            $claims[$k] = $claim->getValue();
        }
        return $claims;
    }

    /**
     * 处理token
     * @param string $token
     * @param string $prefix
     * @return false|string
     */
    public static function handleToken(string $token, string $prefix = 'Bearer'): bool|string
    {
        if($token && str_contains($token, $prefix)) {
            $token = ucfirst($token);
            $arr = explode("{$prefix} ", $token);
            $token = $arr[1] ?? '';
        }
        return $token ?: false;
    }

    /**
     * @param Signer $signer
     * @param Key $key
     * @return Configuration
     */
    public static function getConfiguration(Signer $signer, Key $key): Configuration
    {
        return Configuration::forSymmetricSigner($signer, $key);
    }

    /**
     * @param Signer $signer
     * @param Key $key
     * @return \Lcobucci\JWT\Builder
     */
    public static function getBuilder(Signer $signer, Key $key): \Lcobucci\JWT\Builder
    {
        return self::getConfiguration($signer, $key)->builder();
    }

    /**
     * @return Parser
     */
    public static function getParser(Signer $signer, Key $key): Parser
    {
        return self::getConfiguration($signer, $key)->parser();
    }

    /**
     * @param Signer $signer
     * @param Key $key
     * @param string $token
     * @return bool
     */
    public static function getValidationData(Signer $signer, Key $key, string $token): bool
    {
        $config = self::getConfiguration($signer, $key);
        $parser = $config->parser()->parse($token);
        $claims = $parser->claims()->all();
        $now = new \DateTimeImmutable();

        if ($claims['nbf'] > $now || $claims['exp'] < $now) {
            return false;
        }

        $config->setValidationConstraints(new \Lcobucci\JWT\Validation\Constraint\IdentifiedBy($claims['jti']));
        if (!$config->validator()->validate($parser, ...$config->validationConstraints())) {
            return false;
        }

        return true;
    }
}
