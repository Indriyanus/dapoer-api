-- AlterTable
ALTER TABLE "kehadiran" ADD COLUMN     "latKeluar" DOUBLE PRECISION,
ADD COLUMN     "latMasuk" DOUBLE PRECISION,
ADD COLUMN     "lokasiKeluar" TEXT,
ADD COLUMN     "lokasiMasuk" TEXT,
ADD COLUMN     "longKeluar" DOUBLE PRECISION,
ADD COLUMN     "longMasuk" DOUBLE PRECISION;
