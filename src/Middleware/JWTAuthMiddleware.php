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
 * Description 通用的中间件，只会验证每个应用是否正确
 */
class JWTAuthMiddleware implements MiddlewareInterface
{
    protected HttpResponse $response;
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
            if ($token !== false && $this->jwt->checkToken($token)) {
                $isValidToken = true;
            }
        }

        if ($isValidToken) {
            return $handler->handle($request);
        }

        throw new TokenValidException('Token authentication does not pass', 401);
    }
}
