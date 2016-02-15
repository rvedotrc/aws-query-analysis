require_relative "../lib/aws_policy_simulator"

describe "match on Resource / NotResource" do

  def expect_match(context_resource, statement_resource, statement_notresource = nil)
    expect_result(context_resource, statement_resource, statement_notresource, AwsPolicySimulator::ALLOWED)
  end

  def expect_no_match(context_resource, statement_resource, statement_notresource = nil)
    expect_result(context_resource, statement_resource, statement_notresource, AwsPolicySimulator::NEITHER)
  end

  def expect_result(context_resource, statement_resource, statement_notresource, result)
    ctx = AwsPolicySimulator::RequestContext.new(
      "arn:aws:sqs:eu-west-1:123456789012:root",
      "foo:GetBar",
      context_resource,
    )

    s = { "Effect" => "Allow" }
    s["Resource"] = statement_resource if statement_resource
    s["NotResource"] = statement_notresource if statement_notresource
    doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => s})

    expect(doc.test(ctx)).to eq(result)
  end

  it "matches on Resource" do
    an_arn = "arn:aws:sqs:eu-west-1:123456789012:SomeQueue"
    expect_match(an_arn, an_arn)
    expect_no_match(an_arn, an_arn+"x")
  end

  it "matches on Resource (wildcard)" do
    an_arn = "arn:aws:sqs:eu-west-1:123456789012:SomeQueue"
    expect_match(an_arn, "*")
    expect_match(an_arn, "arn:*") # valid?
    expect_match(an_arn, "arn:aws:sqs:eu-west-1:123456789012:*")
    expect_match(an_arn, "arn:aws:sqs:eu-west-?:123456789012:*")
  end

  it "matches on Resource (list)" do
    an_arn = "arn:aws:sqs:eu-west-1:123456789012:SomeQueue"
    expect_match(an_arn, ["*", "foo"])
    expect_match(an_arn, ["foo", an_arn])
    expect_no_match(an_arn, ["foo", "bar"])
  end

  it "matches on NotResource" do
    an_arn = "arn:aws:sqs:eu-west-1:123456789012:SomeQueue"
    expect_no_match(an_arn, nil, an_arn)
    expect_no_match(an_arn, nil, "*")
    expect_match(an_arn, nil, an_arn+"x")
  end

  it "matches on NotResource (list)" do
    an_arn_1 = "arn:aws:sqs:eu-west-1:123456789012:SomeQueue1"
    an_arn_2 = "arn:aws:sqs:eu-west-1:123456789012:SomeQueue2"
    an_arn_3 = "arn:aws:sqs:eu-west-1:123456789012:SomeQueue3"
    expect_match(an_arn_1, nil, [an_arn_2, an_arn_3])
    expect_no_match(an_arn_2, nil, [an_arn_2, an_arn_3])
  end

  # TODO variables.
  # TODO only for policy version 2012-10-17.
  # "In the Resource element, you can use policy variables in the part of the
  # ARN that identifies the specific resource (that is, in the trailing part
  # of the ARN)."
  # Does this apply to NotResource too? Does it apply to other parts of the
  # ARN? Is it even ARN-aware, or is it just a flat string?

end
