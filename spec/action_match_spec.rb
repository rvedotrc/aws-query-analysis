require_relative "../lib/aws_policy_simulator"

describe "match on Action / NotAction" do

  def expect_match(context_action, statement_action, statement_notaction = nil)
    expect_result(context_action, statement_action, statement_notaction, AwsPolicySimulator::ALLOWED)
  end

  def expect_no_match(context_action, statement_action, statement_notaction = nil)
    expect_result(context_action, statement_action, statement_notaction, AwsPolicySimulator::NEITHER)
  end

  def expect_result(context_action, statement_action, statement_notaction, result)
    ctx = AwsPolicySimulator::RequestContext.new(
      "arn:aws:sqs:eu-west-1:123456789012:root",
      context_action,
      "arn:aws:sqs:eu-west-1:123456789012:SomeQueue",
    )

    s = { "Effect" => "Allow", "Resource" => "*" }
    s["Action"] = statement_action if statement_action
    s["NotAction"] = statement_notaction if statement_notaction
    doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => s})

    expect(doc.test(ctx)).to eq(result)
  end

  it "matches on Action" do
    an_action = "foo:GetBar"
    expect_match(an_action, an_action)
    expect_no_match(an_action, an_action+"x")
  end

  it "matches on Action (wildcard)" do
    an_action = "foo:GetBar"
    expect_match(an_action, "*")
    expect_match(an_action, "foo:*")
    expect_match(an_action, "foo:Get*")
    expect_match(an_action, "foo:GetBar")
    expect_match(an_action, "foo:GetB?r") # valid?
    expect_no_match(an_action, "zoo:GetBar")
    expect_no_match(an_action, "foo:SetBar")
  end

  it "matches on Action (list)" do
    an_action = "foo:GetBar"
    expect_match(an_action, ["*", "foo"])
    expect_match(an_action, ["foo", an_action])
    expect_no_match(an_action, ["foo", "bar"])
  end

  it "matches on NotAction" do
    an_action = "foo:GetBar"
    expect_no_match(an_action, nil, an_action)
    expect_no_match(an_action, nil, "*")
    expect_match(an_action, nil, an_action+"x")
  end

  it "matches on NotAction (list)" do
    an_action_1 = "foo:GetBar1"
    an_action_2 = "foo:GetBar2"
    an_action_3 = "foo:GetBar3"
    expect_match(an_action_1, nil, [an_action_2, an_action_3])
    expect_no_match(an_action_2, nil, [an_action_2, an_action_3])
  end

  # TODO actually case-insensitive?

end
