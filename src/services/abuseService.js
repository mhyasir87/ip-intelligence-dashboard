import axios from "axios";

export const fetchAbuseData = async (ip) => {
  try {

    const response = await axios.get(
      `https://ip-intelligence-dashboard.onrender.com/api/abuse/${ip}`
    );

    return response.data.data;

  } catch (error) {

    console.log("Abuse Service Error:", error);

    throw error;
  }
};