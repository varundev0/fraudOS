import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Login from './pages/Login';
import CaseQueue from './pages/CaseQueue';
import CaseDetail from './pages/CaseDetail';
import './index.css';

const qc = new QueryClient();
const isAuth = () => !!sessionStorage.getItem('fraudos_key');

function Guard({ children }) {
  return isAuth() ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Guard><CaseQueue /></Guard>} />
          <Route path="/case/:caseId" element={<Guard><CaseDetail /></Guard>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
