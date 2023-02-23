using ZenLib;
using System.Linq;

// var a = Zen.Symbolic<uint>();
// var b = Zen.Symbolic<uint>();
// var c1 = b <= 10;
// var c2 = a == 3;
// var c3 = b < a;
// 
// var solution = Zen.And(c1, c2, c3).Solve();
// System.Console.WriteLine("a: " + solution.Get(a));
// System.Console.WriteLine("b: " + solution.Get(b));

Zen<bool> F1(Zen<uint> x, Zen<uint> y)
{
	return x < y;
}
var f1 = new ZenFunction<uint, uint, bool>(F1);
// var output = f1.Evaluate(3, 2);
// System.Console.WriteLine("out:   " + output);

// var input = f1.Find((x, y, result) => Zen.And(y<=3, x<=10, result==true));
// System.Console.WriteLine("in:    " + input);

var inputs = f1.FindAll((x, y, result) => Zen.And(y<=3, x <=10, result==false)).ToList();
System.Console.WriteLine("#in(s): " + inputs.Count);
//System.Console.WriteLine("in(s): " + inputs.Count);

foreach (var input in inputs)
{
	Console.WriteLine(input);
}
