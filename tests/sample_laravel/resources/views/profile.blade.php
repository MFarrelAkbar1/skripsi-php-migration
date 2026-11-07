<div class="bio">{!! $user->bio !!}</div>
<p>{{ $user->name }}</p>
@if ($user->active)
    <span>Active</span>
@endif
