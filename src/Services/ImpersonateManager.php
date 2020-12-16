<?php

namespace Bitapp\Impersonate\Services;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Application;
use Bitapp\Impersonate\Events\LeaveImpersonation;
use Bitapp\Impersonate\Events\TakeImpersonation;
use Bitapp\Impersonate\Exceptions\InvalidUserProvider;
use Bitapp\Impersonate\Exceptions\MissingUserProvider;
use Exception;

class ImpersonateManager
{
    /** @var Application $app */
    private $app;

    public $token;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    /**
     * @param int $id
     * @return \Illuminate\Contracts\Auth\Authenticatable
     * @throws MissingUserProvider
     * @throws InvalidUserProvider
     * @throws ModelNotFoundException
     */
    public function findUserById($id, $guardName = null)
    {
        if (empty($guardName)) {
            $guardName = $this->app['config']->get('auth.default.guard', 'web');
        }

        $providerName = $this->app['config']->get("auth.guards.$guardName.provider");

        if (empty($providerName)) {
            throw new MissingUserProvider($guardName);
        }

        try {
            /** @var UserProvider $userProvider */
            $userProvider = $this->app['auth']->createUserProvider($providerName);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidUserProvider($guardName);
        }

        if (!($modelInstance = $userProvider->retrieveById($id))) {
            $model = $this->app['config']->get("auth.providers.$providerName.model");

            throw (new ModelNotFoundException())->setModel(
                $model,
                $id
            );
        }

        return $modelInstance;
    }

    public function isImpersonating(): bool
    {
        return !empty($this->getImpersonatorId());
    }

    /**
     * @return  int|null
     */
    public function getImpersonatorId()
    {
        return $this->app['auth']->user()->token()->impersonator_id ?? null;
    }

    /**
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function getImpersonator()
    {
        $id = $this->getImpersonatorId();

        return is_null($id) ? null : $this->findUserById($id, $this->getImpersonatorGuardName());
    }

    /**
     * @return string|null
     */
    public function getImpersonatorGuardName()
    {
        return null;
    }

    /**
     * @return string|null
     */
    public function getImpersonatorGuardUsingName()
    {
        return null;
    }

    /**
     * @param \Illuminate\Contracts\Auth\Authenticatable $from
     * @param \Illuminate\Contracts\Auth\Authenticatable $to
     * @param string|null                         $guardName
     * @return bool
     */
    public function take($from, $to, $guardName = null)
    {
        try {
            $this->deferLogout($this->getCurrentAuthGuardName());
            $this->deferLogin($to, $guardName);

            $this->token = $to->createTokenForImpersonator('impersonation', $from)->accessToken;
        } catch (Exception $e) {
            unset($e);
            return false;
        }

        $this->app['events']->dispatch(new TakeImpersonation($from, $to));

        return true;
    }

    public function leave(): bool
    {
        try {
            $impersonated = $this->app['auth']->guard($this->getImpersonatorGuardUsingName())->user();
            $impersonator = $this->getImpersonator();

            $this->deferLogout($this->getCurrentAuthGuardName());
            $this->deferLogin($impersonator, $this->getImpersonatorGuardName());

            $this->token = $impersonator->createToken('impersonated')->accessToken;
        } catch (Exception $e) {
            unset($e);
            return false;
        }

        $this->app['events']->dispatch(new LeaveImpersonation($impersonator, $impersonated));

        return true;
    }

    /**
     * @param $guard
     * @return void
     */
    public function deferLogout($guard = null)
    {
        $this->app['auth']->guard($guard)->logout();
    }

    /**
     * @param $guard
     * @param $user
     * @return void
     */
    public function deferLogin($user, $guard = null)
    {
        $this->app['auth']->guard($guard)->login($user);
    }

    /**
     * @return array|null
     */
    public function getCurrentAuthGuardName()
    {
        $guards = array_keys(config('auth.guards'));

        foreach ($guards as $guard) {
            if ($this->app['auth']->guard($guard)->check()) {
                return $guard;
            }
        }

        return null;
    }

    /**
     * @return string|null
     */
    public function getDefaultGuard()
    {
        return config('auth.defaults.guard');
    }
}
