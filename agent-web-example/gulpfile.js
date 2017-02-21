var gulp = require('gulp'),
    concat = require('gulp-concat'),
    rename = require('gulp-rename'),
    uglify = require('gulp-uglify'),
    uglifycss = require('gulp-uglifycss');

gulp.task('js', function () {
    gulp.src(['./src/js/**/*.js'])
        .pipe(rename('app.min.js'))
        .pipe(uglify())
        .pipe(gulp.dest('dist'));
});

gulp.task('js-lib', function () {
    gulp.src(['./node_modules/agent-web/dist/**/*.min.js'])
        .pipe(rename('lib.js'))
        .pipe(gulp.dest('dist'));
});

gulp.task('css', function () {
    return gulp.src(['./src/css/**/*.css'])
        .pipe(rename('app.min.css'))
        .pipe(uglifycss({
            "maxLineLen": 80,
            "uglyComments": true
        }))
        .pipe(gulp.dest('dist'));
});

gulp.task('html', function () {
    return gulp.src(['./src/**/*.html'])
        .pipe(gulp.dest('dist'));
});

gulp.task('watch', function () {
    gulp.watch('src/js/**/*.js', ['js']);
    gulp.watch('src/css/**/*.css', ['css']);
    gulp.watch('src/**/*.html', ['html']);
    gulp.watch('src/lib/**/*.js', ['js-lib']);
});

gulp.task('default', ['js', 'css', 'html', 'js-lib', 'watch'], function () {

});