<?php

namespace Bitapp\Impersonate\Middleware;

use Closure;
use Bitapp\Impersonate\Services\ImpersonateManager;

class ProtectFromImpersonation
{
    /**
     * Handle an incoming request.
     *
     * @param   \Illuminate\Http\Request  $request
     * @param   \Closure  $next
     * @return  mixed
     */
    public function handle($request, Closure $next)
    {
        $impersonate_manager = app()->make(ImpersonateManager::class);

        if ($impersonate_manager->isImpersonating()) {
            abort(403);
        }

        return $next($request);
    }
}
