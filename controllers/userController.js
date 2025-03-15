import userModel from "../models/userModels.js";
export const getUserData = async (req, res) => {
    try {
        const { userId } = req;
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(400).json({ message: "User does not exist" });
        }
        // const users = await userModel.find();
        return res.status(200).json({ success: true, userData:{
            name: user.name,
            email: user.email,
            isVerified: user.isVerified

        } });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
}