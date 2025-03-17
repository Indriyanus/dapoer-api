-- AlterTable
ALTER TABLE "kehadiran" ADD COLUMN     "latKeluar" DOUBLE PRECISION,
ADD COLUMN     "latMasuk" DOUBLE PRECISION,
ADD COLUMN     "locationKeluar" TEXT,
ADD COLUMN     "locationMasuk" TEXT,
ADD COLUMN     "longKeluar" DOUBLE PRECISION,
ADD COLUMN     "longMasuk" DOUBLE PRECISION;
