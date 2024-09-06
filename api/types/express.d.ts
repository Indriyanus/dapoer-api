import { JwtPayload } from 'jsonwebtoken';

declare module 'express-serve-static-core' {
  interface Request {
    user?: string | JwtPayload; // Sesuaikan tipe ini dengan struktur payload JWT Anda
  }
}
