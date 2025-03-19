"use client";
import React, { useState, ChangeEvent, useEffect } from "react";
import { scanPackage } from "./api/api";

interface PackageJson {
  dependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

const Scan = () => {
  const [jsonData, setJsonData] = useState<PackageJson | null>(null);
  const [scanResult, setScanResult] = useState<string[]>([]);
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files ? e.target.files[0] : null;
    if (selectedFile) {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (e.target && e.target.result) {
          try {
            const jsonContent: PackageJson = JSON.parse(e.target.result as string);
            setJsonData(jsonContent);
          } catch (error) {
            console.error("Error parsing JSON:", error);
            setToast({ message: "Invalid JSON format!", type: "error" });
          }
        }
      };
      reader.readAsText(selectedFile);
    }
  };

  const handleScan = async () => {
    if (jsonData) {
      setIsLoading(true);
      try {
        const result = await scanPackage(jsonData);
        setScanResult(result.issues);
        setToast({
          message: result.issues.length === 1 && result.issues[0] === "No issues found"
            ? "No issues found!"
            : "Security issues detected!",
          type: result.issues.length === 1 && result.issues[0] === "No issues found" ? "success" : "error",
        });
      } catch (error) {
        console.error("Error during scan:", error);
        setToast({ message: "Failed to scan package", type: "error" });
      } finally {
        setIsLoading(false);
      }
    }
  };

  // Auto-dismiss toast after 3 seconds
  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 3000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  return (
    <div className="min-h-screen bg-gray-100 text-gray-900 p-6">
      {/* Header */}
      <header className="bg-blue-600 text-white p-5 rounded-md shadow-md text-center">
        <h1 className="text-3xl font-bold">Package Scanner Tool</h1>
      </header>

      {/* Intro */}
      <section className="my-8 text-center">
        <p className="text-blue-700 text-lg">
          Upload your <code className="font-semibold">package.json</code> file to scan for
          vulnerabilities, malicious scripts, and security risks.
        </p>

        {/* Trusted sources */}
        <div className="mt-4 text-lg">
          <span className="text-gray-700">Install packages from official websites:</span>
          <div className="flex justify-center space-x-4 mt-2">
            <a
              href="https://www.npmjs.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:text-blue-800 hover:underline transition"
            >
              npmjs.com
            </a>
            <a
              href="https://deno.land/x"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:text-blue-800 hover:underline transition"
            >
              deno.land/x
            </a>
          </div>
        </div>
      </section>

      {/* File Upload & Scan */}
      <section className="flex flex-col items-center">
        <label className="w-full max-w-md bg-white border border-gray-300 rounded-lg p-4 shadow-md text-center cursor-pointer hover:bg-gray-50 transition">
          <span className="block text-gray-700 font-medium">Select JSON File</span>
          <input
            type="file"
            accept=".json"
            onChange={handleFileChange}
            className="hidden"
          />
        </label>

        {jsonData && (
          <button
            onClick={handleScan}
            className="mt-6 bg-red-600 text-white px-5 py-2 rounded-lg shadow-md hover:bg-red-700 transition"
          >
            Scan Package
          </button>
        )}

        {/* Loading Spinner */}
        {isLoading && (
          <div className="mt-4 flex items-center">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
            <span className="ml-2 text-blue-600">Scanning...</span>
          </div>
        )}
      </section>

      {/* Scan Results */}
      {scanResult.length > 0 && !isLoading && (
        <section className="mt-6 w-full max-w-lg mx-auto bg-white p-5 rounded-lg shadow-md">
          <h3 className="text-xl font-semibold text-blue-600">Scan Results:</h3>
          <ul className="list-disc pl-6 mt-3 space-y-2">
            {scanResult.map((issue, index) => (
              <li key={index} className="text-gray-800">
                {issue}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Toast Notification */}
      {toast && (
        <div
          className={`fixed bottom-5 left-1/2 transform -translate-x-1/2 px-4 py-2 rounded-md shadow-md text-white ${
            toast.type === "success" ? "bg-green-500" : "bg-red-500"
          }`}
        >
          {toast.message}
        </div>
      )}
    </div>
  );
};

export default Scan;
