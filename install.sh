#!/bin/bash
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
SCRIPT_PATH="$(pwd)/smali_scout.py"
chmod +x "$SCRIPT_PATH"
ln -sf "$SCRIPT_PATH" "$BIN_DIR/scout"
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> ~/.bashrc
  echo "Adicionado $BIN_DIR ao seu PATH no .bashrc"
fi
echo "SmaliScout Core instalado com sucesso como o comando : scout"
echo "Reinicie o terminal para que as alterações do PATH tenham efeito global."
