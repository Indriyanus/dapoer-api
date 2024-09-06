import jwt from "jsonwebtoken"

export const createToken = ({userId, userRole}: {userId: string, userRole: string}) => {
    return jwt.sign({userId, userRole}, "dpng2024", {algorithm: "HS256", expiresIn: "1d"})
}