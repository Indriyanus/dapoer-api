-- AlterTable
ALTER TABLE `pengguna` MODIFY `posisi` ENUM('STAFF', 'LEADER', 'ASMAN', 'MANAGER', 'DIREKTUR', 'KOMISARIS', 'DIREKTUR_UTAMA') NOT NULL;
