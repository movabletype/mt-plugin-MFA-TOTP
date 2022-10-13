interface JQuery {
  mtModal: {
    close: (url?: string) => void;
  };
}

interface Window {
  ScriptURI: string;
  jQuery: typeof jQuery;
}
