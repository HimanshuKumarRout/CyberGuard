import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { SocDataProvider } from './context/SocDataContext';
import AppRoutes from './routes/AppRoutes';

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <SocDataProvider>
          <AppRoutes />
        </SocDataProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
