const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const bcrypt = require("bcrypt");

const hashPassword = async (password) => {
  const saltRound = 10;
  return await bcrypt.hash(password, saltRound);
}

const pengguna = [
  {
    namaDepan: 'Indriyanus',
    namaBelakang: 'Manalor',
    NIK: '931001',
    email: 'indriyanusmanalor.realemail@gmail.com',
    tanggalLahir: new Date('1993-11-12'), // Format tanggal ISO
    posisi: 'CEO', // Sesuai dengan enum Posisi di Prisma schema
    kataSandi: 'abc12345',
    nomorTelepon: '085211336653',
    alamat: 'Cluster Graha Permata Poris Blok C/26'
  }
];

const products = [
  { name: "Dapoer Telekomunikasi", code: "01.01/DPNG/PRO/DTI/2024" },
  { name: "Dapoer Parfum", code: "01.02/DPNG/PRO/DPM/2024" },
  { name: "Dapoer Photography", code: "01.03/DPNG/PRO/DPY/2024" },
  { name: "Dapoer Chemical", code: "01.04/DPNG/PRO/DCL/2024" },
  { name: "Dapoer Website", code: "01.05/DPNG/PRO/DWE/2024" }
];

const notadinas = [
  { name: "Kop Surat", code: "01.01/DPNG/DIN/2024" },
  { name: "Perjalanan Dinas", code: "01.01/DPNG/DIN/SPPD/2024" }
];

async function main() {
  // Seed pengguna
  for (const user of pengguna) {
    const hashedPassword = await hashPassword(user.kataSandi);
    await prisma.pengguna.create({
      data: {
        ...user,
        kataSandi: hashedPassword
      }
    });
  }
  console.log('Data pengguna berhasil disisipkan');

  // Seed products
  for (const product of products) {
    await prisma.product.create({
      data: product,
    });
  }
  console.log('Products berhasil disisipkan');

  // Seed notadinas
  for (const nota of notadinas) {
    await prisma.notadinas.create({
      data: nota,
    });
  }
  console.log('Notadinas berhasil disisipkan');

  // Seed documents
  for (const document of documents) {
    await prisma.document.create({
      data: document,
    });
  }
  console.log('Documents berhasil disisipkan');
}

main()
  .catch(e => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
