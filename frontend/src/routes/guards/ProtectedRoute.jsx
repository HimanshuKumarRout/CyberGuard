import React from 'react';

/**
 * ProtectedRoute: User login requirement has been removed.
 * Directly renders child components without authentication barriers.
 */
export default function ProtectedRoute({ children }) {
  return children;
}
