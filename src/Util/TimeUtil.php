<?php
declare(strict_types=1);

namespace Hyperf\JWTAuth\Util;

use Carbon\Carbon;

/**
 * Author lujihong
 * Description
 */
class TimeUtil
{
    /**
     * Get the Carbon instance for the current time.
     * @return Carbon
     */
    public static function now(): Carbon
    {
        return Carbon::now('UTC');
    }

    /**
     * Get the Carbon instance for the timestamp.
     * @param $timestamp
     * @return Carbon
     */
    public static function timestamp($timestamp): Carbon
    {
        return Carbon::createFromTimestampUTC($timestamp)->timezone('UTC');
    }

    /**
     * Checks if a timestamp is in the past.
     * @param int $timestamp
     * @param int $leeway
     * @return bool
     */
    public static function isPast(int $timestamp, int $leeway = 0): bool
    {
        return static::timestamp($timestamp)->addSeconds($leeway)->isPast();
    }

    /**
     * Checks if a timestamp is in the future.
     * @param int $timestamp
     * @param int $leeway
     * @return bool
     */
    public static function isFuture(int $timestamp, int $leeway = 0): bool
    {
        return static::timestamp($timestamp)->subSeconds($leeway)->isFuture();
    }
}
