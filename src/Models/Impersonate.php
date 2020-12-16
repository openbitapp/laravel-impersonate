<?php

namespace Bitapp\Impersonate\Models;

use Bitapp\Impersonate\PersonalAccessTokenFactory;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Bitapp\Impersonate\Services\ImpersonateManager;
use Illuminate\Container\Container;

trait Impersonate
{
    /**
     * Return true or false if the user can impersonate an other user.
     *
     * @param void
     * @return  bool
     */
    public function canImpersonate()
    {
        return true;
    }

    /**
     * Return true or false if the user can be impersonate.
     *
     * @param void
     * @return  bool
     */
    public function canBeImpersonated()
    {
        return true;
    }

    /**
     * Return true or false if the user can be impersonate by the impersonator.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $impersonator
     * @return  bool
     */
    public function canBeImpersonatedBy(Authenticatable $impersonator)
    {
        return true;
    }

    /**
     * Impersonate the given user.
     *
     * @param Model       $user
     * @param string|null $guardName
     * @return  bool
     */
    public function impersonate(Model $user, $guardName = null)
    {
        return app(ImpersonateManager::class)->take($this, $user, $guardName);
    }

    /**
     * Check if the current user is impersonated.
     *
     * @param void
     * @return  bool
     */
    public function isImpersonated()
    {
        return app(ImpersonateManager::class)->isImpersonating();
    }

    /**
     * Leave the current impersonation.
     *
     * @param void
     * @return  bool
     */
    public function leaveImpersonation()
    {
        if ($this->isImpersonated()) {
            return app(ImpersonateManager::class)->leave();
        }
    }

    /**
     * Create a new personal access token for the user.
     *
     * @param  string  $name
     * @param  array  $scopes
     * @return \Laravel\Passport\PersonalAccessTokenResult
     */
    public function createTokenForImpersonator($name, Authenticatable $impersonator, array $scopes = [])
    {
        return Container::getInstance()->make(PersonalAccessTokenFactory::class)->makeImpersonated(
            $this->getKey(), $impersonator->getKey(), $name, $scopes
        );
    }
}
