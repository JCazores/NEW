import { Navigate, Outlet } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';

/**
 * Props:
 *  adminOnly  — only admin role can enter
 *  permission — a string like 'monitors' | 'vapt' | 'system_health'
 *               If provided, the user must have this permission (or be admin)
 */
export default function ProtectedRoute({ adminOnly = false, permission = null }) {
  const { user, token, isLoading } = useAuthStore();

  // Still verifying token with server
  if (isLoading) {
    return (
      <div style={{
        display:        'flex',
        justifyContent: 'center',
        alignItems:     'center',
        height:         '100vh',
        fontSize:       '18px',
        color:          '#6b7280',
      }}>
        Loading...
      </div>
    );
  }

  // No token or no user → login
  if (!token || !user) {
    return <Navigate to="/login" replace />;
  }

  // Admin-only route but user is not admin → user dashboard
  if (adminOnly && user.role !== 'admin') {
    return <Navigate to="/user/dashboard" replace />;
  }

  // Permission-gated route: check if user has the required permission
  if (permission && user.role !== 'admin') {
    const userPerms = user.permissions ?? [];
    if (!userPerms.includes(permission)) {
      // Redirect to dashboard with a "no access" signal via state
      return <Navigate to="/user/dashboard" replace state={{ noAccess: true }} />;
    }
  }

  return <Outlet />;
}