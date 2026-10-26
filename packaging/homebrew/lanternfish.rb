# Homebrew formula for Lanternfish. Install directly:
#   brew install --formula https://raw.githubusercontent.com/hatimtoor/lanternfish/main/packaging/homebrew/lanternfish.rb
class Lanternfish < Formula
  desc "Free web security testing toolkit that teaches as it goes (authorized testing only)"
  homepage "https://github.com/hatimtoor/lanternfish"
  version "0.5.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.5.1/lanternfish_v0.5.1_darwin_arm64"
      sha256 "7e66ca075445cc82b639f907bdb2b9823d1543bbe88e276135c50e6d3e91a85b"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.5.1/lanternfish_v0.5.1_darwin_amd64"
      sha256 "3dfbd2b516725b07b36d3338632d446346f210f9ed4f8ead6fa114f2c92408b0"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.5.1/lanternfish_v0.5.1_linux_arm64"
      sha256 "6320134be53af658b874a59885756a0a07fcca0d29187b44c17c948348df463a"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.5.1/lanternfish_v0.5.1_linux_amd64"
      sha256 "beb19495896edd81d0e1683a60d9a38b370d596c1867135539dbb26a3c6bc9f8"
    end
  end

  def install
    bin.install Dir["lanternfish_*"].first => "lanternfish"
  end

  test do
    assert_match "lanternfish", shell_output("#{bin}/lanternfish version")
  end
end
