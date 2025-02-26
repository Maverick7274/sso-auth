import mongoose from "mongoose";

const clientSchema = new mongoose.Schema(
	{
		client_id: { type: String, required: true, unique: true },
		client_secret: { type: String, required: true },
		name: { type: String, required: true },
		description: { type: String },
		logo: { type: String },
		redirect_uris: { type: [String], required: true },
		active: { type: Boolean, default: true },
	},
	{ timestamps: true }
);

export default mongoose.model("Client", clientSchema);
