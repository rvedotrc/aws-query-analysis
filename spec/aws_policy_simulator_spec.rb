require_relative "../lib/aws_policy_simulator"

describe "match on Principal" do

  def context_for_principal(principal)
    AwsPolicySimulator::RequestContext.new(
      principal,
      "foo:GetBar",
      "arn:aws:foo:eu-west-1:123456789012:SomeFoo",
    )
  end

  def a_root_user
    { "AWS" => "arn:aws:iam::123456789012:root" }
  end

  def an_iam_user
    { "AWS" => "arn:aws:iam::123456789012:user/someone" }
  end

  def an_iam_role
    { "AWS" => "arn:aws:iam::123456789012:role/something" }
  end

  def a_service(s = "ec2")
    { "Service" => "#{s}.amazonaws.com" }
  end

  def some_services(list)
    { "Service" => list.map {|s| "#{s}.amazonaws.com"} }
  end

  def expect_match(context_principal, statement_principal)
    expect_result(context_principal, statement_principal, AwsPolicySimulator::ALLOWED)
  end

  def expect_no_match(context_principal, statement_principal)
    expect_result(context_principal, statement_principal, AwsPolicySimulator::NEITHER)
  end

  def expect_result(context_principal, statement_principal, result)
    s = { "Effect" => "Allow", "Resource" => "*" }
    s["Principal"] = statement_principal unless statement_principal.nil?
    doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => [s]})

    ctx = context_for_principal(context_principal)

    ans = doc.test(ctx)
    expect(ans).to eq(result)
  end

  it "defaults to matching" do
    expect_match(a_root_user, nil)
    expect_match(an_iam_user, nil)
    expect_match(an_iam_role, nil)
    expect_match(a_service, nil)
  end

  it "matches AWS *" do
    t = { "AWS" => "*" }
    expect_match(a_root_user, t)
    expect_match(an_iam_user, t)
    expect_match(an_iam_role, t)
    expect_no_match(a_service, t) # Is this right?
  end

  it "matches AWS (single)" do
    # TODO, Supports wildcards?
    t = an_iam_user
    expect_no_match(a_root_user, t)
    expect_match(an_iam_user, t)
    expect_no_match(an_iam_role, t)
    expect_no_match(a_service, t)
  end

  it "matches AWS (list)" do
    # TODO, Supports wildcards?
    t = { "AWS" => [ an_iam_user["AWS"], an_iam_role["AWS"] ] }
    expect_no_match(a_root_user, t)
    expect_match(an_iam_user, t)
    expect_match(an_iam_role, t)
    expect_no_match(a_service, t)
  end

  it "matches a service" do
    t = a_service
    expect_no_match(a_root_user, t)
    expect_no_match(an_iam_user, t)
    expect_no_match(an_iam_role, t)
    expect_match(a_service, t)
  end

  it "matches a list of services" do
    t = some_services(%w[ ec2 sns sqs ])
    expect_no_match(a_root_user, t)
    expect_no_match(an_iam_user, t)
    expect_no_match(an_iam_role, t)
    expect_match(a_service("sqs"), t)
    expect_no_match(a_service("rds"), t)
  end

end

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

end

describe "match on Action / NotAction" do

  it "blah" do
    true
  end

end

describe "match on Conditions" do

  it "blah" do
    true
  end

end
