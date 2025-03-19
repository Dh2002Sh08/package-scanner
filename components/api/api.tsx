// components/api/api.tsx
export const scanPackage = async (jsonData: { dependencies?: Record<string, string>; scripts?: Record<string, string> }) => {
  try {
    // Log the API call to check if it's being triggered
    console.log('Calling /api/scan with:', jsonData);

    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ packageJson: jsonData }),
    });

    // Check if the response is okay (status 2xx)
    if (!res.ok) {
      const errorMessage = await res.text(); // Get error message from response
      throw new Error(`Failed to scan package. Server responded with: ${errorMessage}`);
    }

    // Parse the response and return it
    const result = await res.json();
    return result; // Return scan results
  } catch (error) {
    // Log any errors to the console for debugging
    console.error("Error during scan:", error);
    throw error; // Rethrow the error for handling at a higher level
  }
};
