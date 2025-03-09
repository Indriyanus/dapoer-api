-- CreateTable
CREATE TABLE "kehadiran" (
    "id" SERIAL NOT NULL,
    "penggunaId" INTEGER NOT NULL,
    "masuk" TIMESTAMP(3),
    "keluar" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "kehadiran_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "kehadiran_createdAt_penggunaId_idx" ON "kehadiran"("createdAt" DESC, "penggunaId");

-- AddForeignKey
ALTER TABLE "kehadiran" ADD CONSTRAINT "kehadiran_penggunaId_fkey" FOREIGN KEY ("penggunaId") REFERENCES "pengguna"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
