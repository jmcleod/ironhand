# Build script for IronHand

# Build WebUI (placeholder for now)
echo "Building WebUI..."
# cd web && npm install && npm run build && cd ..

# Build Go binary
echo "Building Go binary..."
go build -o bin/ironhand ./cmd/ironhand/main.go
