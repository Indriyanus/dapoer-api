/*
  Warnings:

  - You are about to drop the `samples` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropTable
DROP TABLE `samples`;

-- CreateTable
CREATE TABLE `pengguna` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `namaDepan` VARCHAR(191) NOT NULL,
    `namaBelakang` VARCHAR(191) NOT NULL,
    `NIK` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NOT NULL,
    `tanggalLahir` DATETIME(3) NOT NULL,
    `posisi` ENUM('STAFF', 'LEADER', 'ASMAN', 'MANAGER') NOT NULL,
    `kataSandi` VARCHAR(191) NOT NULL,
    `nomorTelepon` VARCHAR(191) NULL,
    `alamat` VARCHAR(191) NULL,
    `dibuatPada` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `diperbaruiPada` DATETIME(3) NOT NULL,

    UNIQUE INDEX `Pengguna_NIK_key`(`NIK`),
    UNIQUE INDEX `Pengguna_email_key`(`email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
