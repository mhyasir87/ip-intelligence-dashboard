import axios from "axios";

export const fetchCensysData = async (ip) => {
  const response = await axios.get(
    `https://ip-intelligence-dashboard.onrender.com/api/censys/${ip}`
  );

  return response.data;
};