require_relative "../lib/aws_policy_simulator"

describe AwsPolicySimulator::PolicyDocument do

  def allow_all
    { "Resource" => "*", "Action" => "*", "Effect" => "Allow" }
  end

  def deny_all
    { "Resource" => "*", "Action" => "*", "Effect" => "Deny" }
  end

  def deny_none
    { "NotResource" => "*", "Action" => "*", "Effect" => "Deny" }
  end

  def some_context
    AwsPolicySimulator::RequestContext.new(
      {"AWS" => "arn:aws:iam::123456789012:root"},
      "foo:GetBar",
      "arn:aws:foo:eu-west-1:123456789012:SomeFoo",
    )
  end

  it "should default to neither" do
    doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => []})
    ctx = some_context
    ans = doc.test(ctx)
    expect(ans).to eq(AwsPolicySimulator::NEITHER)
  end

  it "should apply Deny" do
    doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => [allow_all,deny_all,allow_all]})
    ctx = some_context
    ans = doc.test(ctx)
    expect(ans).to eq(AwsPolicySimulator::DENIED)
  end

  it "should apply Allow" do
    doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => [deny_none,allow_all,deny_none]})
    ctx = some_context
    ans = doc.test(ctx)
    expect(ans).to eq(AwsPolicySimulator::ALLOWED)
  end

  it "should handle a bare statement" do
    doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => allow_all})
    ctx = some_context
    ans = doc.test(ctx)
    expect(ans).to eq(AwsPolicySimulator::ALLOWED)
  end

end
