/*
  Warnings:

  - The values [CEO] on the enum `Pengguna_posisi` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterTable
ALTER TABLE `pengguna` MODIFY `posisi` ENUM('STAFF', 'LEADER', 'ASMAN', 'MANAGER', 'DIREKTUR', 'KOMISARIS', 'DIREKTUR_UTAMA') NOT NULL;
