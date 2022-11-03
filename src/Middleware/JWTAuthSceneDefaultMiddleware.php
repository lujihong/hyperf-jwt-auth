<?php
declare(strict_types=1);

namespace Hyperf\JWTAuth\Middleware;

use Hyperf\HttpServer\Contract\ResponseInterface as HttpResponse;
use Hyperf\JWTAuth\Util\JWTUtil;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Hyperf\JWTAuth\JWT;
use Hyperf\JWTAuth\Exception\TokenValidException;

/**
 * Author lujihong
 * Description
 */
class JWTAuthSceneDefaultMiddleware implements MiddlewareInterface
{
    protected HttpResponse $response;
    protected string $prefix = 'Bearer';
    protected JWT $jwt;

    public function __construct(HttpResponse $response, JWT $jwt)
    {
        $this->response = $response;
        $this->jwt = $jwt;
    }

    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $isValidToken = false;

        // 根据具体业务判断逻辑走向，这里假设用户携带的token有效
        $token = $request->getHeaderLine('Authorization') ?? '';
        if ($token !== '') {
            $token = JWTUtil::handleToken($token);
            // 验证该token是否为default场景配置生成的
            if ($token !== false && $this->jwt->setScene('default')->checkToken($token, null, true, true)) {
                $isValidToken = true;
            }
        }

        if ($isValidToken) {
            return $handler->handle($request);
        }

        throw new TokenValidException('Token authentication does not pass', 401);
    }
}
