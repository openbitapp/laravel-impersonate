<?php

namespace Bitapp\Impersonate;

use \Laravel\Passport\PersonalAccessTokenFactory as PassportFactory;
use Laravel\Passport\PersonalAccessTokenResult;

class PersonalAccessTokenFactory extends PassportFactory
{
    /**
     * Create a new personal access token.
     *
     * @param  mixed  $userId
     * @param  string  $name
     * @param  array  $scopes
     * @return \Laravel\Passport\PersonalAccessTokenResult
     */
    public function makeImpersonated($userId, $impersonatorId, $name, array $scopes = [])
    {
        $response = $this->dispatchRequestToAuthorizationServer(
            $this->createRequest($this->clients->personalAccessClient(), $userId, $scopes)
        );

        $token = tap($this->findAccessToken($response), function ($token) use ($userId, $impersonatorId, $name) {
            $this->tokens->save($token->forceFill([
                'user_id' => $userId,
                'impersonator_id' => $impersonatorId,
                'name' => $name,
            ]));
        });

        return new PersonalAccessTokenResult(
            $response['access_token'], $token
        );
    }
}