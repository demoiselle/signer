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
    gulp.src(['./src/lib/**/*.js'])
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

gulp.task('default', ['js', 'css', 'html', 'js-lib'], function () {

});