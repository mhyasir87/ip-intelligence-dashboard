import axios from "axios";

export const fetchCensysData = async (ip) => {
  const response = await axios.get(
    `http://localhost:5000/api/censys/${ip}`
  );

  return response.data;
};