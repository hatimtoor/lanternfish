# Homebrew formula for Lanternfish. Install directly:
#   brew install --formula https://raw.githubusercontent.com/hatimtoor/lanternfish/main/packaging/homebrew/lanternfish.rb
class Lanternfish < Formula
  desc "Free web security testing toolkit that teaches as it goes (authorized testing only)"
  homepage "https://github.com/hatimtoor/lanternfish"
  version "0.3.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.3.0/lanternfish_v0.3.0_darwin_arm64"
      sha256 "1dc2724c35091dee36d1d0c2561aeded56653cfc6d8b0c1735f17925008123a6"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.3.0/lanternfish_v0.3.0_darwin_amd64"
      sha256 "422192e7e35003ef873fa2e72f6862666faba3617186b9cc394c578c9ee9e099"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.3.0/lanternfish_v0.3.0_linux_arm64"
      sha256 "7d77d73ba871996900848ff3b6711208084c01621f4cd05d4e8fbfde6f9a0627"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.3.0/lanternfish_v0.3.0_linux_amd64"
      sha256 "0fe62c4c3ac49a73b34b0435ae903952e84e1bca80a637cfa310275f27309219"
    end
  end

  def install
    bin.install Dir["lanternfish_*"].first => "lanternfish"
  end

  test do
    assert_match "lanternfish", shell_output("#{bin}/lanternfish version")
  end
end
