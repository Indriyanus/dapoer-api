/*
  Warnings:

  - You are about to drop the column `notadinasId` on the `document` table. All the data in the column will be lost.
  - The values [Dir_Opersional] on the enum `Pengguna_posisi` will be removed. If these variants are still used in the database, this will fail.
  - You are about to drop the `notadinas` table. If the table is not empty, all the data it contains will be lost.
  - Made the column `productId` on table `document` required. This step will fail if there are existing NULL values in that column.

*/
-- DropForeignKey
ALTER TABLE `document` DROP FOREIGN KEY `Document_notadinasId_fkey`;

-- DropForeignKey
ALTER TABLE `document` DROP FOREIGN KEY `Document_productId_fkey`;

-- AlterTable
ALTER TABLE `document` DROP COLUMN `notadinasId`,
    MODIFY `productId` INTEGER NOT NULL;

-- AlterTable
ALTER TABLE `pengguna` MODIFY `posisi` ENUM('STAFF', 'LEADER', 'ASMAN', 'MANAGER', 'DIREKTUR_OPERASIONAL', 'KOMISARIS', 'CEO') NOT NULL;

-- DropTable
DROP TABLE `notadinas`;

-- CreateTable
CREATE TABLE `image` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(191) NOT NULL,
    `url` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `productId` INTEGER NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `document` ADD CONSTRAINT `Document_productId_fkey` FOREIGN KEY (`productId`) REFERENCES `product`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `image` ADD CONSTRAINT `Image_productId_fkey` FOREIGN KEY (`productId`) REFERENCES `product`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
