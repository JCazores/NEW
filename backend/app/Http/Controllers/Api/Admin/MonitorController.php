<?php
namespace App\Http\Controllers\Api\Admin;
use App\Http\Controllers\Controller;
use App\Models\Monitor;
use App\Models\MonitorRecipient;
use App\Models\User;
use Illuminate\Http\Request;
class MonitorController extends Controller
{
    public function index()
    {
        $monitors = Monitor::with(['user', 'recipients'])
            ->withCount('incidents')
            ->orderByDesc('created_at')
            ->get();
        return response()->json(['data' => $monitors]);
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'user_id'                => 'required|exists:users,id',
            'name'                   => 'required|string|max:100',
            'url'                    => 'required|url|max:500',
            'category'               => 'nullable|string|exists:categories,name',
            'check_interval_seconds' => 'nullable|integer|min:1',
            'recipient_emails'       => 'nullable|array',
            'recipient_emails.*'     => 'email',
        ]);

        $monitor = Monitor::create([
            'user_id'                => $data['user_id'],
            'name'                   => $data['name'],
            'url'                    => $data['url'],
            'category'               => $data['category'] ?? 'Others',
            'check_interval_seconds' => $data['check_interval_seconds'] ?? 2,
        ]);

        if (!empty($data['recipient_emails'])) {
            foreach ($data['recipient_emails'] as $email) {
                MonitorRecipient::create([
                    'monitor_id' => $monitor->id,
                    'email'      => $email,
                ]);
            }
        }

        return response()->json([
            'message' => 'Monitor created successfully.',
            'data'    => $monitor->load('recipients'),
        ], 201);
    }

    public function update(Request $request, Monitor $monitor)
    {
        $data = $request->validate([
            'name'               => 'sometimes|string|max:100',
            'url'                => 'sometimes|url|max:500',
            'category'           => 'sometimes|string|exists:categories,name',
            'is_active'          => 'sometimes|boolean',
            'recipient_emails'   => 'nullable|array',
            'recipient_emails.*' => 'email',
        ]);

        $monitor->update($data);

        if (isset($data['recipient_emails'])) {
            $monitor->recipients()->delete();
            foreach ($data['recipient_emails'] as $email) {
                MonitorRecipient::create([
                    'monitor_id' => $monitor->id,
                    'email'      => $email,
                ]);
            }
        }

        return response()->json([
            'message' => 'Monitor updated successfully.',
            'data'    => $monitor->load('recipients'),
        ]);
    }

    public function destroy(Monitor $monitor)
    {
        $monitor->delete();
        return response()->json(['message' => 'Monitor deleted successfully.']);
    }

    public function toggle(Monitor $monitor)
    {
        $monitor->update(['is_active' => !$monitor->is_active]);

        return response()->json([
            'message' => $monitor->is_active ? 'Monitor resumed.' : 'Monitor paused.',
            'data'    => $monitor,
        ]);
    }

    public function getUsers()
    {
        $users = User::where('role', 'user')
            ->whereIn('status', ['pending', 'registered', 'active'])
            ->orderBy('name')
            ->get(['id', 'name', 'email', 'status']);

        return response()->json(['data' => $users]);
    }
}