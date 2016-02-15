require_relative "../lib/aws_policy_simulator"

describe AwsPolicySimulator::PartialResult do

  it "should provide ALLOWED" do
    v = AwsPolicySimulator::ALLOWED
    expect(v.allowed?).to be_truthy
    expect(v.denied?).to be_falsy
    expect(v.to_s).to match(/ALLOWED/)
    expect(v.inspect).to match(/ALLOWED/)
  end

  it "should provide DENIED" do
    v = AwsPolicySimulator::DENIED
    expect(v.allowed?).to be_falsy
    expect(v.denied?).to be_truthy
    expect(v.to_s).to match(/DENIED/)
    expect(v.inspect).to match(/DENIED/)
  end

  it "should provide NEITHER" do
    v = AwsPolicySimulator::NEITHER
    expect(v.allowed?).to be_falsy
    expect(v.denied?).to be_falsy
    expect(v.to_s).to match(/NEITHER/)
    expect(v.inspect).to match(/NEITHER/)
  end

  it "should add partial results" do
    y = AwsPolicySimulator::ALLOWED
    n = AwsPolicySimulator::DENIED
    p = AwsPolicySimulator::NEITHER

    expect(y).to eq(y)
    expect(y).not_to eq(n)
    expect(y).not_to eq(p)

    expect(n).not_to eq(y)
    expect(n).to eq(n)
    expect(n).not_to eq(p)

    expect(p).not_to eq(y)
    expect(p).not_to eq(n)
    expect(p).to eq(p)

    expect(y + y).to eq(y)
    expect(y + n).to eq(n)
    expect(y + p).to eq(y)

    expect(n + y).to eq(n)
    expect(n + n).to eq(n)
    expect(n + p).to eq(n)

    expect(p + y).to eq(y)
    expect(p + n).to eq(n)
    expect(p + p).to eq(p)
  end

end
