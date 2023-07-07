
import nodemailer from 'nodemailer';

export async function sendEmail(to: string, subject: string, html: string) {
  let transporter = nodemailer.createTransport({
    host: 'smtp-mail.outlook.com',
    port: 587,
    secure: false, // true para a porta 465, false para outras portas
    requireTLS: true, // isso forçará o Nodemailer a usar STARTTLS
    auth: {
      user: process.env.SMTP_USER, // usuário do SMTP
      pass: process.env.SMTP_PASSWORD, // senha do SMTP
    },
});

  await transporter.sendMail({
    from: '"Horóscopo App" <ehb_software@outlook.com>', // remetente
    to: to,
    subject: subject,
    html: html,
  });
}
