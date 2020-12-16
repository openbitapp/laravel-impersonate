<?php

namespace Bitapp\Impersonate\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Bitapp\Impersonate\Services\ImpersonateManager;

class ImpersonateController extends Controller
{
    /** @var ImpersonateManager */
    protected $manager;

    /**
     * ImpersonateController constructor.
     */
    public function __construct()
    {
        $this->manager = app()->make(ImpersonateManager::class);
        
        $guard = $this->manager->getDefaultSessionGuard();
        $this->middleware('auth:' . $guard)->only('take');
    }

    /**
     * @param int         $id
     * @param string|null $guardName
     * @return  \Illuminate\Http\JsonResponse
     * @throws  \Exception
     */
    public function take(Request $request, $id, $guardName = null)
    {
        $guardName = $guardName ?? $this->manager->getDefaultSessionGuard();

        // Cannot impersonate yourself
        if ($id == $request->user()->getAuthIdentifier() && ($this->manager->getCurrentAuthGuardName() == $guardName)) {
            abort(403);
        }

        // Cannot impersonate again if you're already impersonate a user
        if ($this->manager->isImpersonating()) {
            abort(403);
        }

        if (!$request->user()->canImpersonate()) {
            abort(403);
        }

        $userToImpersonate = $this->manager->findUserById($id, $guardName);

        if ($userToImpersonate->canBeImpersonatedBy($request->user())) {
            if ($this->manager->take($request->user(), $userToImpersonate, $guardName)) {
                $takeToken = $this->manager->token;
                if (!empty($takeToken)) {
                    return response()->json([
                        'data' => [
                            'token' => $takeToken,
                        ],
                    ]);
                }
            }
        }

        return abort(403);
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    public function leave()
    {
        if (!$this->manager->isImpersonating()) {
            abort(403);
        }

        $this->manager->leave();

        $leaveToken = $this->manager->token;
        if (!empty($leaveToken)) {
            return response()->json([
                'data' => [
                    'token' => $leaveToken,
                ],
            ]);
        }

        return abort(403);
    }
}
