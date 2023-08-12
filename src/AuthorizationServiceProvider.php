<?php

namespace Celysium\Authorization;

use Celysium\Request\Exceptions\BadRequestHttpException;
use Celysium\Request\Facades\RequestBuilder;
use Celysium\Authenticate\Facades\Authenticate;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;
use Illuminate\Http\Request;

class AuthorizationServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->registerGates();
    }

    protected function registerGates()
    {
        /** @var Request $request */
        Gate::define('role', function ($user, string $role) use ($request) {
            $roles = $request->header('roles');

            return in_array($role, $roles);
        });

        Gate::define('permission', function ($user, string $permission) {
            $id = Authenticate::id();
            $permissions = Cache::remember("permission_$id", 120, function () use ($permission) {
                return RequestBuilder::request('api_gateway')
                    ->get('/internal/auth/permissions')
                    ->onError(fn($response) => throw new BadRequestHttpException($response))
                    ->json('data');
            });

            return in_array($permission, array_column($permissions, 'name'));
        });
    }
}