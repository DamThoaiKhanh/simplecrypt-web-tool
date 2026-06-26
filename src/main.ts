import "./style.css";
import appHtml from "./app.html?raw";

import { base64ToBytes, bytesToBase64, SimpleCrypt } from "./simpleCrypt";

import {
  DEFAULT_OUTPUT_FILENAME,
  ENCRYPT_COMPRESSION_MODE,
  ENCRYPT_INTEGRITY_MODE,
  SIMPLECRYPT_KEY,
} from "./config";

type Tab = "file" | "text";
type Mode = "encrypt" | "decrypt";

type OutputState = {
  bytes: Uint8Array | null;
  filename: string;
  mime: string;
};

const app = query<HTMLDivElement>("#app");
app.innerHTML = appHtml;

const fileInput = query<HTMLInputElement>("#fileInput");
const fileName = query<HTMLSpanElement>("#fileName");
const fileOutput = query<HTMLTextAreaElement>("#fileOutput");
const fileStatus = query<HTMLParagraphElement>("#fileStatus");

const textInput = query<HTMLTextAreaElement>("#textInput");
const textOutput = query<HTMLTextAreaElement>("#textOutput");
const textStatus = query<HTMLParagraphElement>("#textStatus");

const fileTabButton = query<HTMLButtonElement>("#fileTabButton");
const textTabButton = query<HTMLButtonElement>("#textTabButton");
const filePanel = query<HTMLElement>("#filePanel");
const textPanel = query<HTMLElement>("#textPanel");

const fileOutputState: OutputState = createEmptyOutputState();
const textOutputState: OutputState = createEmptyOutputState();

bindUi();

function bindUi(): void {
  fileTabButton.addEventListener("click", () => setActiveTab("file"));
  textTabButton.addEventListener("click", () => setActiveTab("text"));

  fileInput.addEventListener("change", onFileChanged);

  query<HTMLButtonElement>("#encryptFileTextButton").addEventListener(
    "click",
    () => void processUploadedTextFile("encrypt"),
  );
  query<HTMLButtonElement>("#decryptFileBase64Button").addEventListener(
    "click",
    () => void processUploadedTextFile("decrypt"),
  );
  query<HTMLButtonElement>("#copyFileOutputButton").addEventListener(
    "click",
    () => void copyOutput(fileOutput, fileStatus),
  );
  query<HTMLButtonElement>("#downloadFileOutputButton").addEventListener(
    "click",
    () => downloadOutput(fileOutput, fileStatus, fileOutputState),
  );

  query<HTMLButtonElement>("#encryptTextButton").addEventListener(
    "click",
    () => void processText("encrypt"),
  );
  query<HTMLButtonElement>("#decryptTextButton").addEventListener(
    "click",
    () => void processText("decrypt"),
  );
  query<HTMLButtonElement>("#copyTextOutputButton").addEventListener(
    "click",
    () => void copyOutput(textOutput, textStatus),
  );
  query<HTMLButtonElement>("#downloadTextOutputButton").addEventListener(
    "click",
    () => downloadOutput(textOutput, textStatus, textOutputState),
  );
}

function setActiveTab(tab: Tab): void {
  const isFileTab = tab === "file";

  fileTabButton.classList.toggle("active", isFileTab);
  textTabButton.classList.toggle("active", !isFileTab);

  fileTabButton.setAttribute("aria-selected", String(isFileTab));
  textTabButton.setAttribute("aria-selected", String(!isFileTab));

  filePanel.classList.toggle("active", isFileTab);
  textPanel.classList.toggle("active", !isFileTab);

  filePanel.hidden = !isFileTab;
  textPanel.hidden = isFileTab;
}

function onFileChanged(): void {
  const file = fileInput.files?.[0];
  fileName.textContent = file
    ? `${file.name} (${formatBytes(file.size)})`
    : "No file selected";
  resetOutput(fileOutput, fileOutputState);
  setStatus(fileStatus, "Ready.");
}

function createCrypt(): SimpleCrypt {
  const crypt = new SimpleCrypt(SIMPLECRYPT_KEY);
  crypt.compressionMode = ENCRYPT_COMPRESSION_MODE;
  crypt.protectionMode = ENCRYPT_INTEGRITY_MODE;
  return crypt;
}

function timestampForFileName(date = new Date()): string {
  const pad = (value: number) => String(value).padStart(2, "0");

  const yyyy = date.getFullYear();
  const mm = pad(date.getMonth() + 1);
  const dd = pad(date.getDate());
  const hh = pad(date.getHours());
  const mi = pad(date.getMinutes());
  const ss = pad(date.getSeconds());

  return `${yyyy}${mm}${dd}_${hh}${mi}${ss}`;
}

async function processUploadedTextFile(mode: Mode): Promise<void> {
  try {
    const file = fileInput.files?.[0];
    if (!file) {
      setStatus(fileStatus, "Please choose a file first.", true);
      return;
    }

    const crypt = createCrypt();
    const fileText = await file.text();

    if (mode === "encrypt") {
      const encrypted = await crypt.encryptToByteArray(
        new TextEncoder().encode(fileText),
      );
      const base64 = bytesToBase64(encrypted);

      fileOutput.value = base64;
      setOutputState(
        fileOutputState,
        new TextEncoder().encode(base64),
        `${file.name}.encrypted.txt`,
        "text/plain;charset=utf-8",
      );
      setStatus(
        fileStatus,
        "Encrypted uploaded text file successfully. Output is Base64.",
      );
      return;
    }

    const decrypted = await crypt.decryptToByteArray(
      base64ToBytes(fileText.trim()),
    );
    if (!assertNoCryptError(crypt, fileOutput, fileStatus, fileOutputState))
      return;

    const plainText = new TextDecoder().decode(decrypted);
    fileOutput.value = plainText;
    setOutputState(
      fileOutputState,
      new TextEncoder().encode(plainText),
      removeEncryptedSuffix(file.name),
      "text/plain;charset=utf-8",
    );
    setStatus(fileStatus, "Decrypted uploaded Base64 text file successfully.");
  } catch (error) {
    setStatus(fileStatus, toErrorMessage(error), true);
  }
}

async function processText(mode: Mode): Promise<void> {
  try {
    const input = textInput.value;
    if (!input.trim()) {
      setStatus(textStatus, "Input is empty.", true);
      return;
    }

    const crypt = createCrypt();

    if (mode === "encrypt") {
      const encrypted = await crypt.encryptToByteArray(
        new TextEncoder().encode(input),
      );
      const base64 = bytesToBase64(encrypted);

      textOutput.value = base64;
      setOutputState(
        textOutputState,
        new TextEncoder().encode(base64),
        `encrypted_${timestampForFileName()}.txt`,
        "text/plain;charset=utf-8",
      );
      setStatus(textStatus, "Encrypted text successfully. Output is Base64.");
      return;
    }

    const decrypted = await crypt.decryptToByteArray(
      base64ToBytes(input.trim()),
    );
    if (!assertNoCryptError(crypt, textOutput, textStatus, textOutputState))
      return;

    const plainText = new TextDecoder().decode(decrypted);
    textOutput.value = plainText;
    setOutputState(
      textOutputState,
      new TextEncoder().encode(plainText),
      `decrypted_${timestampForFileName()}.txt`,
      "text/plain;charset=utf-8",
    );
    setStatus(textStatus, "Decrypted Base64 successfully.");
  } catch (error) {
    setStatus(textStatus, toErrorMessage(error), true);
  }
}

async function copyOutput(
  outputElement: HTMLTextAreaElement,
  statusElement: HTMLParagraphElement,
): Promise<void> {
  if (!outputElement.value) {
    setStatus(statusElement, "Nothing to copy.", true);
    return;
  }

  await navigator.clipboard.writeText(outputElement.value);
  setStatus(statusElement, "Output copied to clipboard.");
}

function downloadOutput(
  outputElement: HTMLTextAreaElement,
  statusElement: HTMLParagraphElement,
  state: OutputState,
): void {
  if (!state.bytes) {
    if (!outputElement.value) {
      setStatus(statusElement, "Nothing to download.", true);
      return;
    }

    setOutputState(
      state,
      new TextEncoder().encode(outputElement.value),
      DEFAULT_OUTPUT_FILENAME,
      "text/plain;charset=utf-8",
    );
  }

  const bytes = state.bytes;
  if (!bytes) {
    setStatus(statusElement, "Nothing to download.", true);
    return;
  }

  const blob = new Blob([bytes.slice()], { type: state.mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = state.filename;
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();

  window.setTimeout(() => {
    URL.revokeObjectURL(url);
    link.remove();
  }, 1000);

  setStatus(statusElement, `Download started: ${state.filename}.`);
}

function createEmptyOutputState(): OutputState {
  return {
    bytes: null,
    filename: DEFAULT_OUTPUT_FILENAME,
    mime: "text/plain;charset=utf-8",
  };
}

function resetOutput(
  outputElement: HTMLTextAreaElement,
  state: OutputState,
): void {
  outputElement.value = "";
  state.bytes = null;
  state.filename = DEFAULT_OUTPUT_FILENAME;
  state.mime = "text/plain;charset=utf-8";
}

function setOutputState(
  state: OutputState,
  bytes: Uint8Array,
  filename: string,
  mime: string,
): void {
  state.bytes = bytes;
  state.filename = filename;
  state.mime = mime;
}

function assertNoCryptError(
  crypt: SimpleCrypt,
  outputElement: HTMLTextAreaElement,
  statusElement: HTMLParagraphElement,
  state: OutputState,
): boolean {
  if (crypt.lastError === "No error") return true;
  resetOutput(outputElement, state);
  setStatus(statusElement, crypt.lastError, true);
  return false;
}

function query<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(`Missing element: ${selector}`);
  return element;
}

function removeEncryptedSuffix(filename: string): string {
  if (filename.endsWith(".base64.txt")) return filename.slice(0, -11);
  if (filename.endsWith(".enc.txt")) return filename.slice(0, -8);
  if (filename.endsWith(".encrypted.txt")) return filename.slice(0, -14);
  if (filename.endsWith(".enc")) return filename.slice(0, -4);
  return `${filename}.decrypted.txt`;
}

function setStatus(
  statusElement: HTMLParagraphElement,
  message: string,
  isError = false,
): void {
  statusElement.textContent = message;
  statusElement.classList.toggle("error", isError);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
