<?php

namespace App\Http\Controllers;

use App\Http\Requests\User\StoreUserRequest;
use App\Http\Requests\User\UpdateUserRequest;
use App\Http\Resources\UserResource;
use App\Http\Resources\UserResourceCollection;
use App\Repositories\Contracts\UserRepository;
use App\Models\User;

class UserController extends Controller
{
    protected $userRepository;

    public function __construct(UserRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    public function index()
    {
        $user = $this->userRepository->findBy();

        return new UserResourceCollection($user);
    }

    public function store(StoreUserRequest $request)
    {
        $user = $this->userRepository->save($request->all());

        return new UserResource($user);
    }

    public function update(UpdateUserRequest $request, User $user)
    {

        $user = $this->userRepository->update($user, $request->all());

        return new UserResource($user);
    }

    public function show($id)
    {
        $user = $this->userRepository->findOne($id);

        return new UserResource($user);
    }

    public function destroy(User $user)
    {
        $this->userRepository->delete($user);

        return response()->json(null, 204);
    }
}
