/*
  Warnings:

  - The values [DIREKTUR_OPERASIONAL] on the enum `Pengguna_posisi` will be removed. If these variants are still used in the database, this will fail.

*/
-- DropForeignKey
ALTER TABLE `document` DROP FOREIGN KEY `Document_productId_fkey`;

-- AlterTable
ALTER TABLE `document` ADD COLUMN `notadinasId` INTEGER NULL,
    MODIFY `productId` INTEGER NULL;

-- AlterTable
ALTER TABLE `pengguna` MODIFY `posisi` ENUM('STAFF', 'LEADER', 'ASMAN', 'MANAGER', 'Dir_Opersional', 'KOMISARIS', 'CEO') NOT NULL;

-- CreateTable
CREATE TABLE `notadinas` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(191) NOT NULL,
    `code` VARCHAR(191) NOT NULL,

    UNIQUE INDEX `Notadinas_code_key`(`code`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `document` ADD CONSTRAINT `Document_productId_fkey` FOREIGN KEY (`productId`) REFERENCES `product`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `document` ADD CONSTRAINT `Document_notadinasId_fkey` FOREIGN KEY (`notadinasId`) REFERENCES `notadinas`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
