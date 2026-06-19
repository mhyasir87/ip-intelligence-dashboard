import axios from "axios";

export const fetchShodanData = async (ip) => {

  const response = await axios.get(
    `http://localhost:5000/api/shodan/${ip}`
  );

  return response.data;
};