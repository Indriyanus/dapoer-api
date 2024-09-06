const nodemailer =  require("nodemailer")

export const transporter = nodemailer.createTransport({
    service: "gmail",
    auth : {
        user: "ptdapoerpoesatnoesantaragroup@gmail.com",
        pass: "jtvrdcwdkrvsjvcg"
    },
    tls: {
        rejectUnauthorized: false
    }
})
