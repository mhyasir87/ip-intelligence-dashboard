import axios from "axios";

export const fetchBlacklistData = async (ip) => {
  const response = await axios.get(
    `/api/blacklists/${ip}`
  );

  return response.data;
};